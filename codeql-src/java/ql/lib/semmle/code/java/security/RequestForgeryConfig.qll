/**
 * Provides a taint-tracking configuration characterising request-forgery risks.
 *
 * Only import this directly from .ql files, to avoid the possibility of polluting the Configuration hierarchy accidentally.
 */

import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.RequestForgery

/**
 * DEPRECATED: Use `RequestForgeryConfiguration` module instead.
 *
 * A taint-tracking configuration characterising request-forgery risks.
 */
deprecated class RequestForgeryConfiguration extends TaintTracking::Configuration {
  RequestForgeryConfiguration() { this = "Server-Side Request Forgery" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource and
    // Exclude results of remote HTTP requests: fetching something else based on that result
    // is no worse than following a redirect returned by the remote server, and typically
    // we're requesting a resource via https which we trust to only send us to safe URLs.
    not source.asExpr().(MethodAccess).getCallee() instanceof UrlConnectionGetInputStreamMethod
  }

  override predicate isSink(DataFlow::Node sink) { sink instanceof RequestForgerySink }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    any(RequestForgeryAdditionalTaintStep r).propagatesTaint(pred, succ)
  }

  override predicate isSanitizer(DataFlow::Node node) { node instanceof RequestForgerySanitizer }
}

/**
 * A taint-tracking configuration characterising request-forgery risks.
 */
module RequestForgeryConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource and
    // Exclude results of remote HTTP requests: fetching something else based on that result
    // is no worse than following a redirect returned by the remote server, and typically
    // we're requesting a resource via https which we trust to only send us to safe URLs.
    not source.asExpr().(MethodAccess).getCallee() instanceof UrlConnectionGetInputStreamMethod
  }

  predicate isSink(DataFlow::Node sink) { 
    sink instanceof RequestForgerySink
    // or 
    // exists (m(sink))
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    any(RequestForgeryAdditionalTaintStep r).propagatesTaint(pred, succ)
  }

  predicate isBarrier(DataFlow::Node node) { node instanceof RequestForgerySanitizer }
}

module RequestForgeryFlow = TaintTracking::Global<RequestForgeryConfig>;
