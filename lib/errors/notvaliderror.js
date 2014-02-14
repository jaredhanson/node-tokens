/**
 * `NotValidError` error.
 *
 * @api public
 */
function NotValidError(message) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'NotValidError';
  this.message = message;
  this.code = 'ENOTVALID';
}

/**
 * Inherit from `Error`.
 */
NotValidError.prototype.__proto__ = Error.prototype;


/**
 * Expose `NotValidError`.
 */
module.exports = NotValidError;
