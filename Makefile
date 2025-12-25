reg:
	docker build -t registry.mix.local/mixer/single-auth .
	docker push registry.mix.local/mixer/single-auth

up-store:
	docker compose up auth-database auth-redis

run:
	go run ./cmd/auth/auth.go