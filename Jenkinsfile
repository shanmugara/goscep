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

    stage('Determine next version') {
          when { branch 'main' }
          steps {
            // Calculate next patch semver tag. If no tag exists, start from v0.0.1
            // Use Groovy to fetch tags and compute the next version so we can reliably set
            // an env var (avoids writing/sourcing a file and needing stash/unstash).
            script {
              // ensure tags are available
              sh 'git fetch --tags'

              def latest = sh(script: 'git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0"', returnStdout: true).trim()
              echo "Latest tag: ${latest}"

              def ver = latest.replaceFirst(/^v/, '')
              def parts = ver.tokenize('.')
              def major = (parts.size() > 0) ? parts[0].toInteger() : 0
              def minor = (parts.size() > 1) ? parts[1].toInteger() : 0
              def patch = (parts.size() > 2) ? parts[2].toInteger() : 0
              patch = patch + 1

              env.NEW_TAG = "v${major}.${minor}.${patch}"
              echo "NEW_TAG=${env.NEW_TAG}"
            }
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
          def dockerPath = "shanmugara/goscep-server"
          def shortSha = (env.GIT_COMMIT != null && env.GIT_COMMIT.length() >= 8) ? env.GIT_COMMIT.take(8) : null
          //def imageTag = shortSha ?: "${env.BUILD_NUMBER ?: 'local'}"
          def imageName = "${dockerPath}:${env.NEW_TAG}"

          echo "Building Docker image ${imageName}"
          sh "docker build -t ${imageName} ."

          // also tag as latest locally
          // sh "docker tag ${imageName} goscep:latest || true"

          // Optionally push to registry (commented out). To enable pushing, configure credentials in Jenkins
          // and uncomment the following lines, replacing <registry>/<repo> with your registry.
          // sh "docker tag ${imageName} <registry>/<repo>:${imageTag}"
          withCredentials([usernamePassword(credentialsId: 'dockerhub-creds', usernameVariable: 'REG_USER', passwordVariable: 'REG_PASS')]) {
          sh "docker login -u $REG_USER -p $REG_PASS docker.io"
          //sh "docker push <registry>/<repo>:${imageTag}"
          sh "docker push ${imageName}"
         }
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

