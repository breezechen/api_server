# server
Server in go.


# How to compile


```
# 1. Install depends

glide install

# 2. Build
go build

# 3. Setup mysql
docker run --name mattermost-mysql -p 3306:3306 -e MYSQL_ROOT_PASSWORD=mostest -e MYSQL_USER=mmuser -e MYSQL_PASSWORD=mostest -e MYSQL_DATABASE=mattermost_test -d mysql:5.7 > /dev/null;

# 4. Run server
./server

```
