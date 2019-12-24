.. image:: https://badge.fury.io/py/chalice-cognito-auth.svg
    :target: https://badge.fury.io/py/chalice-cognito-auth
.. image:: https://travis-ci.org/stealthycoin/chalice-cognito-auth.svg?branch=master
    :target: https://travis-ci.org/stealthycoin/chalice-cognito-auth

Purpose
=======

A Library for setting up login routes in a Chalice app.


Basic Usage
===========

Below is an example of a basic application making use of a Cognito User Pool.

First set up a new Chalice app::

  $ chalice new-project test-auth
  $ cd test-auth


Next we add ``chalice-cognito-auth`` as a dependency::

  $ echo "chalice-cognito-auth" >> requirements.txt


Now update the ``app.py`` file to configure a default user pool handler.


.. code:: python

    from chalice import Chalice

    import chalice_cognito_auth


    app = Chalice(app_name='test-auth')

    app.experimental_feature_flags.update([
	'BLUEPRINTS',
    ])

    user_pool_handler = chalice_cognito_auth.default_user_pool_handler()
    app.register_blueprint(user_pool_handler.blueprint)


    @app.route('/whoami', authorizer=user_pool_handler.auth)
    def index():
	return {
	    'username': user_pool_handler.current_user
	}


This will create a ``UserPoolHandler`` object using the environment variables
``APP_CLIENT_ID`` for the Cognito Userpool application client id. ``POOL_ID``
for the ID of the Cognito Userpool itself. And ``AWS_REGION`` for the
region. ``AWS_REGION`` is set by the AWS Lambda runtime, but the other two we
need to set ourselves. Update the file ``.chalice/config.json`` to look
something like the following::

    {
	"version": "2.0",
	"app_name": "test-auth",
	"environment_variables": {
	    "APP_CLIENT_ID": "...client id here...",
	    "POOL_ID": "...pool id here..."
	},
	"stages": {
	    "dev": {
		"api_gateway_stage": "api"
	    }
	}
    }


Substitute the client id and pool id values for ones that match an existing
cognito user pool you have and can use for testing.

Now deploy the application using::

  $ chalice deploy
  Creating deployment package.
  Updating policy for IAM role: test-auth-dev
  Updating lambda function: test-auth-dev
  Updating lambda function: test-auth-dev-UserPoolAuth
  Updating rest API
  Resources deployed:
    - Lambda ARN: arn:aws:lambda:us-west-2:...:function:test-auth-dev
    - Lambda ARN: arn:aws:lambda:us-west-2:...:function:test-auth-dev-UserPoolAuth
    - Rest API URL: https://id.execute-api.us-west-2.amazonaws.com/api/

Now that it has been deployed we can access the API using the Rest API
URL. chalice-cognito-auth injects a ``login`` route which accepts a ``POST``
request with a JSON payload containing the two keys ``username`` and
``password``. Make sure your configured userpool has a user in it that can be
used for testing and send something like the following::

  $ curl -X POST -H Content-Type:application/json https://id.execute-api.us-west-2.amazonaws.com/api/login -d '{"username":"StealthyCoin", "password": "secret"}'
  {"id_token":"...","refresh_token":"...","access_token":"...","token_type":"Bearer"}


The above JSON response contains all the tokens needed to send authorized
requests. To test our authorizer we will use the ``whoami`` route which simply
takes a request and either rejects it if unauthorized, or sends back the
username associated with the request. To do this we will send a ``GET`` request
with an ``Authorization`` header with the value of our ``id_token`` from the
result JSON above.

In my case::

  $ curl -H Authorization:...id token here... https://id.execute-api.us-west-2.amazonaws.com/api/whoami
  {"username":"StealthyCoin"}

Which sends back JSON object with the username that goes with my id token.

To check that a requset with a bad authorization token is rejected, run the
following curl command::

  $ curl -H Authorization:foobar https://id.execute-api.us-west-2.amazonaws.com/api/whoami
  {"Message":"User is not authorized to access this resource"}
