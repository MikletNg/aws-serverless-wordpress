region=us-east-1
profile=default
stack="*"
clean:
	rm -rf node_modules **/node_modules **/*.js **/*.d.ts
build:
	yarn run build
init:
	yarn install
deploy: build
	npx cdk deploy $(stack) --require-approval never --profile $(profile)
destroy:
	npx cdk destroy $(stack) --force --profile $(profile)
cdk-upgrade:
	yarn upgrade --scope @aws-cdk --latest
	yarn upgrade aws-cdk --latest
	yarn install
easy-rsa-init:
	mkdir -p lib/cert
	cd lib/cert &&\
	git clone https://github.com/OpenVPN/easy-rsa.git
gen-cert:
	cd lib/cert/easy-rsa/easyrsa3 &&\
	./easyrsa init-pki &&\
	./easyrsa build-ca nopass &&\
	./easyrsa build-server-full server nopass &&\
	./easyrsa build-client-full client nopass &&\
	cp pki/ca.crt ../../ &&\
	cp pki/issued/server.crt ../../ &&\
	cp pki/private/server.key ../../ &&\
	cp pki/issued/client.crt ../../ &&\
	cp pki/private/client.key ../../
import-cert:
	cd lib/cert &&\
	echo "\nServer Certificate ARN:" &&\
	aws acm import-certificate \
	--certificate fileb://server.crt \
	--private-key fileb://server.key \
	--certificate-chain fileb://ca.crt \
	--query 'CertificateArn' --output text --region $(region) --profile $(profile) &&\
	echo "\nClient Certificate ARN:" &&\
	aws acm import-certificate \
	--certificate fileb://client.crt \
	--private-key fileb://client.key \
	--certificate-chain fileb://ca.crt \
	--query 'CertificateArn' --output text --region $(region) --profile $(profile)