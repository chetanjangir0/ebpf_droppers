## to test the code 

## 1. Build and compile
```sh
go generate
go build -o tcp-drop
```

## 2. Start a simple HTTP server on port 4040
```sh
python3 -m http.server 4040
# or use netcat
nc -l 4040
```

## 3. Run your ebpf program 
```sh
# by default works for port 4040
sudo ./tcp-drop
```

## 4. Try to connect (should fail/timeout)
```sh
# This should hang/timeout because packets are dropped
curl http://localhost:4040

# Or with timeout
curl --max-time 5 http://localhost:4040

# Or using netcat
nc -v localhost 4040
```
