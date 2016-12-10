test:
	go test -v -race

cover:
	rm -rf *.coverprofile
	go test -v -coverprofile=jwt.coverprofile
	gover
	go tool cover -html=jwt.coverprofile