'use strict';
const signingKey = '*****'; // TODO: Change in AWS Console after deployed

// Lambda Event Payload = REQUEST
exports.handler = function(event, context, callback) {
  var token = event.headers.Authorization;
  const nJwt = require('./njwt');
  nJwt.verify(token, signingKey, function(err, verifiedJwt) {
    if (err) {
      callback('Unauthorized');
    } else {
      callback(null, generatePolicy('user', 'Allow', event.methodArn, verifiedJwt.body));
    }
  });
};

// Help function to generate an IAM policy
var generatePolicy = function(principalId, effect, resource, verifiedJwt) {
  var authResponse = {};

  authResponse.principalId = principalId;
  if (effect && resource) {
    var policyDocument = {};
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = [];
    var statementOne = {};
    statementOne.Action = 'execute-api:Invoke';
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }

  // Optional output with custom properties of the String, Number or Boolean type.
  authResponse.context = verifiedJwt;
  return authResponse;
};
