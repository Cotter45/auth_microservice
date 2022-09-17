# GRPC Auth Server

This is a simple GRPC server that can be used to authenticate users against a
sqlite database. I'm kind of tired of writing auth logic over and over again for 
test apps, so I'm just going to write it once and use it everywhere. It still needs a 
lot of work and refactoring, but it's a good start and so far looks like it'll be free!

This is a pretty simple app so far, it creates basic JWT tokens for users
and updates whether or not they are logged in. The JWT's are valid for 15 minutes, and
there isn't much information about the user stored in the db. This should work more than well 
enough for basic testing.

The idea is to make this a bit more secure over time and add more relevant details to the user 
object. I'm still learning GRPC so if you're reading this and have any suggestions, please let me know!

## TODO
- Add certificates for TLS
- Add more user information to the db
- Add better error handling
- Add tests
- Add more documentation
