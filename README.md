# aws-infraestructure-test

python3 -m venv venv

source venv/bin/activate

pip install -r infrastructure/requirements.txt

Si el stack fallo 


aws cloudformation delete-stack --stack-name LambdaStack-dev


cdk deploy LambdaStack-dev
