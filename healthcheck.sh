# Accept the 52 error code as valid because the grpc
# server can't respond to curl requests. If the server
# was not running, we would receive a different error code.
curl -f $1
if [ 52 -eq $? ]; then
  exit 0
else
  exit 1
fi;
