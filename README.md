To test it dowmload the source code and open the cmd in that folder and type "node server.js" it would start the server on http://localhost:3000 there is a basic frontend to test the system to register, login and update user roles

To test user access use this -> curl -H "Authorization: Bearer your-token" http://localhost:3000/user, curl -H "Authorization: Bearer your-token" http://localhost:3000/admin

you have to run this in bash terminal with the auth token that was generated during registration or login.
