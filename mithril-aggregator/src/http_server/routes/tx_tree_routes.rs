use serde::{Deserialize, Serialize};
use warp::Filter;

use crate::http_server::routes::middlewares;
use crate::http_server::routes::router::RouterState;

/// Query parameters of the `tx-tree/range` route.
#[derive(Deserialize, Serialize, Debug)]
struct TxTreeRangeQueryParams {
    /// Range start block number (a multiple of `BlockRange::LENGTH`).
    start: u64,
    /// Resolve against the certificate certified at-or-below this block number.
    up_to_block_number: u64,
    /// `v1` or `v2`.
    version: String,
}

/// Query parameters of the `tx-tree/frontier` route.
#[derive(Deserialize, Serialize, Debug)]
struct TxTreeFrontierQueryParams {
    /// Resolve against the certificate certified at-or-below this block number.
    up_to_block_number: u64,
    /// `v1` or `v2`.
    version: String,
    /// Return ranges whose start is `>= from_start` (pagination cursor).
    #[serde(default)]
    from_start: Option<u64>,
    /// Maximum number of ranges to return in this page.
    #[serde(default)]
    limit: Option<usize>,
}

pub fn routes(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    tx_tree_range(router_state).or(tx_tree_frontier(router_state))
}

/// GET /tx-tree/range
fn tx_tree_range(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path!("tx-tree" / "range")
        .and(warp::get())
        .and(warp::query::<TxTreeRangeQueryParams>())
        .and(middlewares::with_logger(router_state))
        .and(middlewares::with_tx_tree_service(router_state))
        .and_then(handlers::tx_tree_range)
}

/// GET /tx-tree/frontier
fn tx_tree_frontier(
    router_state: &RouterState,
) -> impl Filter<Extract = (impl warp::Reply + use<>,), Error = warp::Rejection> + Clone + use<> {
    warp::path!("tx-tree" / "frontier")
        .and(warp::get())
        .and(warp::query::<TxTreeFrontierQueryParams>())
        .and(middlewares::with_logger(router_state))
        .and(middlewares::with_tx_tree_service(router_state))
        .and_then(handlers::tx_tree_frontier)
}

mod handlers {
    use slog::{Logger, debug, warn};
    use std::{convert::Infallible, sync::Arc};
    use warp::http::StatusCode;

    use mithril_common::entities::BlockNumber;

    use crate::http_server::routes::reply;
    use crate::services::{TxTreeService, TxTreeVersion};
    use crate::unwrap_to_internal_server_error;

    use super::{TxTreeFrontierQueryParams, TxTreeRangeQueryParams};

    pub async fn tx_tree_range(
        params: TxTreeRangeQueryParams,
        logger: Logger,
        tx_tree_service: Arc<TxTreeService>,
    ) -> Result<impl warp::Reply, Infallible> {
        debug!(
            logger, ">> tx_tree_range";
            "start" => params.start, "up_to_block_number" => params.up_to_block_number,
            "version" => &params.version
        );

        let Some(version) = TxTreeVersion::parse(&params.version) else {
            warn!(logger, "tx_tree_range::bad_request");
            return Ok(reply::bad_request(
                "invalid_version".to_string(),
                "version must be 'v1' or 'v2'".to_string(),
            ));
        };

        let range = unwrap_to_internal_server_error!(
            tx_tree_service
                .range(
                    BlockNumber(params.start),
                    BlockNumber(params.up_to_block_number),
                    version,
                )
                .await,
            logger => "tx_tree_range::error"
        );

        match range {
            Some(range) => Ok(reply::json(&range, StatusCode::OK)),
            None => {
                warn!(logger, "tx_tree_range::not_found");
                Ok(reply::empty(StatusCode::NOT_FOUND))
            }
        }
    }

    pub async fn tx_tree_frontier(
        params: TxTreeFrontierQueryParams,
        logger: Logger,
        tx_tree_service: Arc<TxTreeService>,
    ) -> Result<impl warp::Reply, Infallible> {
        debug!(
            logger, ">> tx_tree_frontier";
            "up_to_block_number" => params.up_to_block_number, "version" => &params.version
        );

        let Some(version) = TxTreeVersion::parse(&params.version) else {
            warn!(logger, "tx_tree_frontier::bad_request");
            return Ok(reply::bad_request(
                "invalid_version".to_string(),
                "version must be 'v1' or 'v2'".to_string(),
            ));
        };

        let frontier = unwrap_to_internal_server_error!(
            tx_tree_service
                .frontier(
                    BlockNumber(params.up_to_block_number),
                    version,
                    params.from_start.map(BlockNumber),
                    params.limit,
                )
                .await,
            logger => "tx_tree_frontier::error"
        );

        match frontier {
            Some(frontier) => Ok(reply::json(&frontier, StatusCode::OK)),
            None => {
                warn!(logger, "tx_tree_frontier::not_found");
                Ok(reply::empty(StatusCode::NOT_FOUND))
            }
        }
    }
}
