pipeline {

    agent any

    environment {
        APP_NAME    = "trivy-poc-app"
        AWS_REGION  = "ap-south-1"
        ECR_ACCOUNT = "471112521862"
        EMAIL_TO    = "s.harisankar21122002@gmail.com"

        ECR_URL     = "${ECR_ACCOUNT}.dkr.ecr.${AWS_REGION}.amazonaws.com"
        ECR_IMAGE   = "${ECR_URL}/${APP_NAME}:${BUILD_NUMBER}"
        IMAGE_NAME  = "${APP_NAME}:${BUILD_NUMBER}"
        REPORT_DIR  = "${WORKSPACE}/reports"
        REPO_JSON   = "${REPORT_DIR}/repo-scan.json"
        FS_JSON     = "${REPORT_DIR}/fs-scan.json"
        IMAGE_JSON  = "${REPORT_DIR}/image-scan.json"
        HTML_REPORT = "${REPORT_DIR}/trivy-report.html"
        CACHE_DIR   = "/var/lib/jenkins/.trivy-cache"
    }

    options {
        timestamps()
        buildDiscarder(logRotator(numToKeepStr: '5'))
        timeout(time: 60, unit: 'MINUTES')
    }

    stages {

        stage('1. Checkout') {
            steps {
                checkout scm
                sh '''
                    echo "Commit: $(git log --oneline -1)"
                    ls -la
                '''
            }
        }

        stage('2. Setup') {
            steps {
                sh '''
                    mkdir -p ${REPORT_DIR}
                    mkdir -p ${CACHE_DIR}
                    echo "Trivy: $(trivy --version)"

                    if [ ! -f "${CACHE_DIR}/db/metadata.json" ]; then
                        echo "Downloading Trivy DB..."
                        trivy image \
                            --download-db-only \
                            --cache-dir ${CACHE_DIR}
                    else
                        echo "✅ Trivy DB already cached"
                    fi
                '''
            }
        }

        stage('3. Trivy Repo Scan') {
            steps {
                sh '''
                    echo "=== REPO SCAN ==="
                    trivy repo \
                        --cache-dir     ${CACHE_DIR} \
                        --skip-db-update \
                        --scanners      secret,misconfig,vuln \
                        --format        json \
                        --output        ${REPO_JSON} \
                        --exit-code     0 \
                        . || true

                    echo "--- Console Summary ---"
                    trivy repo \
                        --cache-dir     ${CACHE_DIR} \
                        --skip-db-update \
                        --scanners      secret,misconfig,vuln \
                        --format        table \
                        --exit-code     0 \
                        . || true

                    echo "✅ Repo scan done"
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'reports/repo-scan.json',
                                     allowEmptyArchive: true
                }
            }
        }

        stage('4. Trivy Filesystem Scan') {
            steps {
                sh '''
                    echo "=== FILESYSTEM SCAN ==="
                    trivy fs \
                        --cache-dir     ${CACHE_DIR} \
                        --skip-db-update \
                        --scanners      vuln,secret,misconfig \
                        --format        json \
                        --output        ${FS_JSON} \
                        --exit-code     0 \
                        . || true

                    echo "--- Console Summary ---"
                    trivy fs \
                        --cache-dir     ${CACHE_DIR} \
                        --skip-db-update \
                        --scanners      vuln,secret,misconfig \
                        --format        table \
                        --exit-code     0 \
                        . || true

                    echo "✅ Filesystem scan done"
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'reports/fs-scan.json',
                                     allowEmptyArchive: true
                }
            }
        }

        stage('5. Docker Build') {
            steps {
                sh '''
                    echo "=== DOCKER BUILD ==="
                    docker build -t ${IMAGE_NAME} .
                    echo "✅ Image built: ${IMAGE_NAME}"
                    docker images | grep ${APP_NAME}
                '''
            }
        }

        stage('6. Trivy Image Scan') {
            steps {
                sh '''
                    echo "=== IMAGE SCAN ==="
                    trivy image \
                        --cache-dir     ${CACHE_DIR} \
                        --skip-db-update \
                        --scanners      vuln,secret,misconfig \
                        --format        json \
                        --output        ${IMAGE_JSON} \
                        --exit-code     0 \
                        ${IMAGE_NAME} || true

                    echo "--- Console Summary ---"
                    trivy image \
                        --cache-dir     ${CACHE_DIR} \
                        --skip-db-update \
                        --scanners      vuln,secret,misconfig \
                        --format        table \
                        --exit-code     0 \
                        ${IMAGE_NAME} || true

                    echo "✅ Image scan done"
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'reports/image-scan.json',
                                     allowEmptyArchive: true
                }
            }
        }

        stage('7. Push to ECR') {
            steps {
                withCredentials([[
                    $class: 'AmazonWebServicesCredentialsBinding',
                    credentialsId: 'aws-creds',
                    accessKeyVariable: 'AWS_ACCESS_KEY_ID',
                    secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
                ]]) {
                    sh '''
                        echo "=== PUSH TO ECR ==="
                        aws ecr get-login-password \
                            --region ${AWS_REGION} \
                            | docker login \
                                --username AWS \
                                --password-stdin ${ECR_URL}

                        aws ecr describe-repositories \
                            --repository-names ${APP_NAME} \
                            --region ${AWS_REGION} 2>/dev/null \
                        || aws ecr create-repository \
                            --repository-name ${APP_NAME} \
                            --region ${AWS_REGION}

                        docker tag ${IMAGE_NAME} ${ECR_IMAGE}
                        docker push ${ECR_IMAGE}
                        echo "✅ Pushed: ${ECR_IMAGE}"
                    '''
                }
            }
        }

        stage('8. Run Container') {
            steps {
                sh '''
                    echo "=== RUN CONTAINER ==="
                    docker stop ${APP_NAME} 2>/dev/null || true
                    docker rm   ${APP_NAME} 2>/dev/null || true

                    docker run -d \
                        --name    ${APP_NAME} \
                        --restart unless-stopped \
                        -p 5000:5000 \
                        ${IMAGE_NAME}

                    sleep 3
                    docker ps | grep ${APP_NAME}
                    echo "✅ Container running on port 5000"
                '''
            }
        }

        stage('9. Generate HTML Report') {
            steps {
                sh '''
                    echo "=== HTML REPORT ==="
                    python3 ${WORKSPACE}/generate_report.py \
                        ${REPO_JSON} \
                        ${FS_JSON} \
                        ${IMAGE_JSON} \
                        ${HTML_REPORT} \
                        "${APP_NAME}" \
                        "${BUILD_NUMBER}" \
                        "${IMAGE_NAME}"

                    ls -lh ${REPORT_DIR}/
                    echo "✅ Report generated"
                '''

                publishHTML([
                    allowMissing:          true,
                    alwaysLinkToLastBuild: true,
                    keepAll:               true,
                    reportDir:             'reports',
                    reportFiles:           'trivy-report.html',
                    reportName:            'Trivy Security Report'
                ])
            }
        }

        stage('10. Send Email') {
            steps {
                script {
                    def report = readFile("${env.HTML_REPORT}")
                    emailext(
                        subject: "[Trivy] ${env.APP_NAME} Build #${env.BUILD_NUMBER} — ${currentBuild.currentResult}",
                        body: report,
                        mimeType: 'text/html',
                        to: "${env.EMAIL_TO}",
                        attachmentsPattern: 'reports/*.json'
                    )
                    echo "✅ Email sent to ${env.EMAIL_TO}"
                }
            }
        }

    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**/*',
                             allowEmptyArchive: true
            sh '''
                docker rmi ${IMAGE_NAME} || true
                docker image prune -f    || true
            '''
        }
        success {
            echo "✅ PIPELINE PASSED!"
        }
        failure {
            emailext(
                subject: "❌ FAILED — ${env.APP_NAME} #${env.BUILD_NUMBER}",
                body: "<h2 style='color:red'>Pipeline Failed!</h2><p>Check: <a href='${env.BUILD_URL}'>${env.BUILD_URL}</a></p>",
                mimeType: 'text/html',
                to: "${env.EMAIL_TO}"
            )
        }
    }
}
