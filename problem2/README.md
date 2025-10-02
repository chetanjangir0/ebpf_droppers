## to test the code 

## 1. Build and compile
```sh
go generate
go build -o process-drop .
```

## 2. Terminal 1: Run the eBPF program (for the process curl)
```sh
sudo ./process-drop -process curl
```

## 3. Terminal 2: Start the servers 
```sh
python3 -m http.server 4040 &
python3 -m http.server 8080 &
```

## 3. Terminal 3: Test with curl
```sh
curl http://localhost:4040  # Should work
curl http://localhost:8080  # Should fail/hang
```
