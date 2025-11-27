pipeline {
  agent any
  
  environment {
    //Use Pipeline Utility Steps plugin to read information from pom.xml into env variables
    REVISION = "1.0.${env.BUILD_ID}"
    IMAGE = readMavenPom().getArtifactId()
    VERSION = readMavenPom().getVersion()
  }
  
  stages {

    stage('clean_workspace_and_checkout_source') {
      steps {
        deleteDir()
      }
    }
    stage('Maven Install') { 
      agent {
        docker {
          image 'maven:3.5.0'
          args '-v /root/.m2:/root/.m2'
        }

      }

      steps {
        sh 'mvn clean package -Dmaven.test.skip=true'
        stash(name: 'app', includes: 'target/*.jar')
      }
    } 

    stage('Docker Build') {
      agent any
      steps {
        unstash 'app'
        sh 'docker build -t chicocx/auth-server:${REVISION} .'
        sh 'docker build -t chicocx/auth-server:latest .'
      }
    }
    stage('Docker Push') {
      agent any
      steps {
        withCredentials(bindings: [usernamePassword(credentialsId: 'dockerhub', passwordVariable: 'dockerHubPassword', usernameVariable: 'dockerHubUser')]) {
          sh "docker login -u ${env.dockerHubUser} -p ${env.dockerHubPassword}"
          sh 'docker push chicocx/auth-server:${REVISION}'
          sh 'docker push chicocx/auth-server:latest'
        }

      }
    }
  }
  
}
