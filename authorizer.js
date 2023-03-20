const { CognitoJwtVerifier } = require('aws-jwt-verify');
const COGNITO_USERPOOL_ID = process.env.COGNITO_USERPOOL_ID;
const COGNITO_WEB_CLIENT_ID = process.env.COGNITO_WEB_CLIENT_ID;

const jwtVerifier = CognitoJwtVerifier.create({
  userPoolId: COGNITO_USERPOOL_ID,
  tokenUse: 'id',
  clientId: COGNITO_WEB_CLIENT_ID,
});

const generatePolicy = (principalId, effect, resource) => {
  let authResponse = {};
  authResponse.principalId = principalId;

  if (effect && resource) {
    let policyDocument = {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: effect,
          Resource: resource,
          Action: 'execute-api:Invoke',
        },
      ],
    };

    authResponse.policyDocument = policyDocument;
  }

  // can add additional data here
  authResponse.context = {
    foo: 'bar',
  };
  console.log(JSON.stringify(authResponse));

  return authResponse;
};

exports.handler = async (event, context, cb) => {
  // lambda authorizer code
  let token = event.authorizationToken; // this will access authorizer header from the request and get token
  // validate the token
  try {
    const payload = await jwtVerifier.verify(token);
    console.log(JSON.stringify(payload));
    cb(null, generatePolicy('user', 'Allow', event.methodArn));
  } catch (err) {
    cb('Error: Invalid token');
  }
};
