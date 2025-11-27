FROM openjdk:8u151-jdk-alpine
RUN apk add -U tzdata
RUN cp /usr/share/zoneinfo/America/Sao_Paulo /etc/localtime
RUN apk del -U tzdata

RUN mkdir /app

COPY /target/auth-server.jar /app

CMD ["java","-Dspring.profiles.active=prod","-Duser.timezone=America/Sao_Paulo", "-Dspring.config.location=file:/app/config/application.yml" , "-jar" ,"/app/auth-server.jar"]