go run main.go init
go run main.go start > server.log 2>&1 &
sleep 5
cat server.log
