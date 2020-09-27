profile=isengard
clean:
	rm -rf node_modules **/node_modules **/*.js **/*.d.ts
build:
	yarn run build
init:
	yarn install
deploy: build
	npx cdk deploy --require-approval never --profile $(profile)
destroy:
	npx cdk destroy --force --profile $(profile)
cdk-upgrade:
	yarn upgrade --scope @aws-cdk --latest
	yarn upgrade aws-cdk --latest
	yarn install