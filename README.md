Backend of the application

1. Clone the repository
2. Add the pdf file to /src
3. docker build -t sschmi129infobackend .
4. docker compose up
5. add sql database or restore
   docker cp databasedump.sql nameOfContainer:/var/lib/postgresql/data/ 
6. Add the content of FileForNGINX.txt to /swag/config/nginx/nginx.conf
   http{
     ***
     FileForNGINX.txt
     ***
   }
