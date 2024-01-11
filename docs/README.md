# demo-cryptree

## Usage

まず authentication のために ipfs をローカルで立ち上げる

```sh
ipfs daemon
```

サーバーを以下のコマンドで立ち上げる

```sh
uvicorn main:app --reload
```

以下へアクセスして確認可能  
http://localhost:8000/docs

なんか足りなかったら適宜 pip install お願いします

## Version

```sh
ipfs version
```
