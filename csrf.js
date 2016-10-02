module.exports = function csrf(options) {
  options = options || {};
  var value = options.value || defaultValue;

  function defaultValue(req) {
    return (req.body && req.body._csrf)
        || (req.query && req.query._csrf)
        || (req.headers['x-csrf-token'])
        || (req.headers['x-xsrf-token']);
  }

  function checkToken(token, secret) {
    if ('string' != typeof token) return false;
    return token === createToken(token.slice(0, 10), secret);
  }

  function saltedToken(secret) {
    return createToken(generateSalt(10), secret);
  }

  function createToken(salt, secret) {
    return salt + crypto
            .createHash('sha1')
            .update(salt + secret)
            .digest('base64');
  }

  function generateSalt(length) {
    var i, r = [];
    for (i = 0; i < length; ++i) {
      r.push(SALTCHARS[Math.floor(Math.random() * SALTCHARS.length)]);
    }
    return r.join('');
  }

  var SALTCHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

  return function(req, res, next){
    
    // already have one
    var secret = req.session._csrfSecret;
    if (secret) return createToken(secret);

    // generate secret
    uid(24, function(err, secret){
      if (err) return next(err);
      req.session._csrfSecret = secret;
      createToken(secret);
    });
    
    // generate the token
    function createToken(secret) {
      var token;

      // lazy-load token
      req.csrfToken = function csrfToken() {
        return token || (token = saltedToken(secret));
      };
      
      // compatibility with old middleware
      Object.defineProperty(req.session, '_csrf', {
        configurable: true,
        get: function() {
          console.warn('req.session._csrf is deprecated, use req.csrfToken() instead');
          return req.csrfToken();
        }
      });
      
      // ignore these methods
      if ('GET' == req.method || 'HEAD' == req.method || 'OPTIONS' == req.method) return next();
      
      // determine user-submitted value
      var val = value(req);
      
      // check
      if (!checkToken(val, secret)) return next(utils.error(403));
      
      next();
    }
  }
};
