## 起動方法

```
docker-compose up -d
```

## 遊び方

以下の3つのエンドポイントがあります。

### `http://localhost:4567/hint` 

暗号化しているトークンの中身を教えてくれます

### `http://localhost:4567/token` 

トークンを生成します

### `http://localhost:4567/check?token=` 

トークンの確認をします クエリパラメータで渡します
