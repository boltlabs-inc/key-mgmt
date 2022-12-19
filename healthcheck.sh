# Accept the 52 error code as valid because the grpc
# server can't respond to curl requests. If the server
# was not running, we would receive a different error code.
curl -f $1
if [ 52 -eq $? ]; then
  exit 0
elif [ 1 -eq $? ]; then
  # Workaround for servers without TLS running
  RESULT=$( (curl $1) 2>&1)
  FOUND=$(echo $RESULT | grep "Received HTTP/0.9 when not allowed" | wc -l)
  if [ 1 -eq $FOUND ]; then
    exit 0
  else
    exit 1
  fi;
else
  exit 1
fi;
