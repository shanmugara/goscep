pipeline {
  agent any

  // NOTE: Jenkins must be configured to build on push (webhook) or use Multibranch Pipeline.
  // This pipeline only performs the Docker build when the job is running for branch `main`.

  stages {
    stage('Checkout') {
      steps {
        // Use the default SCM checkout configured for this job
        checkout scm
      }
    }

    stage('Build Docker image') {
      // Run only for main branch (works for Multibranch Pipeline where BRANCH_NAME is set).
      // Also allow execution when BRANCH_NAME is not set but GIT_BRANCH ends with /main (classic jobs).
      when {
        anyOf {
          branch 'main'
          expression {
            return (env.BRANCH_NAME == null) || (env.BRANCH_NAME == 'main') || (env.GIT_BRANCH != null && env.GIT_BRANCH.endsWith('/main'))
          }
        }
      }
      steps {
        script {
          // Determine tag: prefer short git commit if available, else use build number
          def shortSha = (env.GIT_COMMIT != null && env.GIT_COMMIT.length() >= 8) ? env.GIT_COMMIT.take(8) : null
          def imageTag = shortSha ?: "${env.BUILD_NUMBER ?: 'local'}"
          def imageName = "goscep:${imageTag}"

          echo "Building Docker image ${imageName}"
          sh "docker build -t ${imageName} ."

          // also tag as latest locally
          sh "docker tag ${imageName} goscep:latest || true"

          // Optionally push to registry (commented out). To enable pushing, configure credentials in Jenkins
          // and uncomment the following lines, replacing <registry>/<repo> with your registry.
          // sh "docker tag ${imageName} <registry>/<repo>:${imageTag}"
          // withCredentials([usernamePassword(credentialsId: 'registry-creds', usernameVariable: 'REG_USER', passwordVariable: 'REG_PASS')]) {
          //   sh "docker login -u $REG_USER -p $REG_PASS <registry>"
          //   sh "docker push <registry>/<repo>:${imageTag}"
          //   sh "docker push <registry>/<repo>:latest"
          // }
        }
      }
    }
  }

  post {
    success {
      echo 'Docker build finished successfully.'
    }
    failure {
      echo 'Docker build failed.'
    }
  }
}

