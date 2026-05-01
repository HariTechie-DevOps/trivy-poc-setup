pipeline {

    agent any

    // ── CHANGE ONLY THESE 3 VALUES ──────────────────────────
    environment {
        APP_NAME    = "trivy-poc-app"
        AWS_REGION  = "ap-south-1"
        ECR_ACCOUNT = "471112521862"       // 12-digit AWS account ID
        EMAIL_TO    = "s.harisankar21122002@gmail.com"       // your gmail

        // ── DO NOT CHANGE BELOW ──────────────────────────────
        ECR_URL     = "${ECR_ACCOUNT}.dkr.ecr.${AWS_REGION}.amazonaws.com"
        ECR_IMAGE   = "${ECR_URL}/${APP_NAME}:${BUILD_NUMBER}"
        IMAGE_NAME  = "${APP_NAME}:${BUILD_NUMBER}"
        REPORT_DIR  = "${WORKSPACE}/reports"
        REPO_JSON   = "${REPORT_DIR}/repo-scan.json"
        FS_JSON     = "${REPORT_DIR}/fs-scan.json"
        IMAGE_JSON  = "${REPORT_DIR}/image-scan.json"
        HTML_REPORT = "${REPORT_DIR}/trivy-report.html"
        CACHE_DIR   = "${WORKSPACE}/.trivy-cache"
    }

    options {
        timestamps()
        buildDiscarder(logRotator(numToKeepStr: '5'))
        timeout(time: 40, unit: 'MINUTES')
    }

    stages {

        // ════════════════════════════════════════════
        // STAGE 1 — CHECKOUT CODE FROM GITHUB
        // ════════════════════════════════════════════
        stage('1. Checkout') {
            steps {
                checkout scm
                sh '''
                    echo "──────────────────────────"
                    echo " CHECKOUT DONE"
                    echo "──────────────────────────"
                    echo "Branch : $(git rev-parse --abbrev-ref HEAD)"
                    echo "Commit : $(git log --oneline -1)"
                    echo "Files  :"
                    ls -la
                '''
            }
        }

        // ════════════════════════════════════════════
        // STAGE 2 — SETUP REPORTS FOLDER + TRIVY DB
        // Trivy is already installed on EC2 manually
        // We just create folders + update DB cache
        // ════════════════════════════════════════════
        stage('2. Setup') {
            steps {
                sh '''
                    echo "──────────────────────────"
                    echo " SETUP"
                    echo "──────────────────────────"

                    # Create report and cache directories
                    mkdir -p ${REPORT_DIR}
                    mkdir -p ${CACHE_DIR}

                    # Trivy already installed — just verify
                    echo "Trivy version: $(trivy --version)"

                    # Download/update vuln DB into cache
                    # This is cached so 2nd build onwards is fast
                    echo "Updating vulnerability database..."
                    trivy image \
                        --download-db-only \
                        --cache-dir ${CACHE_DIR}

                    echo "✅ Setup done"
                '''
            }
        }

        // ════════════════════════════════════════════
        // STAGE 3 — TRIVY REPO SCAN
        // What it scans:
        //   - Hardcoded secrets in code files
        //   - Vulnerable package versions
        //     (requirements.txt, package.json etc)
        //   - IaC misconfigs (Dockerfile, k8s yaml)
        // ════════════════════════════════════════════
        stage('3. Trivy Repo Scan') {
            steps {
                sh '''
                    echo "──────────────────────────"
                    echo " TRIVY REPO SCAN"
                    echo "──────────────────────────"

                    # Save full result as JSON (used in HTML report)
                    trivy repo \
                        --cache-dir ${CACHE_DIR} \
                        --scanners  secret,misconfig,vuln \
                        --format    json \
                        --output    ${REPO_JSON} \
                        --exit-code 0 \
                        . || true

                    # Print summary to Jenkins console log
                    echo ""
                    echo "SUMMARY:"
                    trivy repo \
                        --cache-dir ${CACHE_DIR} \
                        --scanners  secret,misconfig,vuln \
                        --format    table \
                        --exit-code 0 \
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

        // ════════════════════════════════════════════
        // STAGE 4 — TRIVY FILESYSTEM SCAN
        // What it scans:
        //   - Every file in workspace
        //   - Dockerfile misconfigurations
        //   - Secrets in any config files
        //   - Vulnerable packages in lock files
        // ════════════════════════════════════════════
        stage('4. Trivy Filesystem Scan') {
            steps {
                sh '''
                    echo "──────────────────────────"
                    echo " TRIVY FILESYSTEM SCAN"
                    echo "──────────────────────────"

                    trivy fs \
                        --cache-dir ${CACHE_DIR} \
                        --scanners  vuln,secret,misconfig \
                        --format    json \
                        --output    ${FS_JSON} \
                        --exit-code 0 \
                        . || true

                    echo ""
                    echo "SUMMARY:"
                    trivy fs \
                        --cache-dir ${CACHE_DIR} \
                        --scanners  vuln,secret,misconfig \
                        --format    table \
                        --exit-code 0 \
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

        // ════════════════════════════════════════════
        // STAGE 5 — BUILD DOCKER IMAGE
        // ════════════════════════════════════════════
        stage('5. Docker Build') {
            steps {
                sh '''
                    echo "──────────────────────────"
                    echo " DOCKER BUILD"
                    echo " Image: ${IMAGE_NAME}"
                    echo "──────────────────────────"

                    docker build -t ${IMAGE_NAME} .

                    echo "✅ Image built: ${IMAGE_NAME}"
                    docker images | grep ${APP_NAME}
                '''
            }
        }

        // ════════════════════════════════════════════
        // STAGE 6 — TRIVY IMAGE SCAN
        // What it scans:
        //   - All OS packages inside the image
        //     (debian/ubuntu/alpine packages)
        //   - All app libraries installed
        //     (python pip, node npm etc)
        //   - Secrets baked into image layers
        //   - Image misconfigurations
        // ════════════════════════════════════════════
        stage('6. Trivy Image Scan') {
            steps {
                sh '''
                    echo "──────────────────────────"
                    echo " TRIVY IMAGE SCAN"
                    echo " Target: ${IMAGE_NAME}"
                    echo "──────────────────────────"

                    trivy image \
                        --cache-dir ${CACHE_DIR} \
                        --scanners  vuln,secret,misconfig \
                        --format    json \
                        --output    ${IMAGE_JSON} \
                        --exit-code 0 \
                        ${IMAGE_NAME} || true

                    echo ""
                    echo "SUMMARY:"
                    trivy image \
                        --cache-dir ${CACHE_DIR} \
                        --scanners  vuln,secret,misconfig \
                        --format    table \
                        --exit-code 0 \
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

        // ════════════════════════════════════════════
        // STAGE 7 — PUSH TO AWS ECR
        // ════════════════════════════════════════════
        stage('7. Push to ECR') {
            steps {
                withCredentials([[
                    $class: 'AmazonWebServicesCredentialsBinding',
                    credentialsId: 'aws-creds',
                    accessKeyVariable: 'AWS_ACCESS_KEY_ID',
                    secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
                ]]) {
                    sh '''
                        echo "──────────────────────────"
                        echo " PUSH TO ECR"
                        echo "──────────────────────────"

                        # Login to ECR
                        aws ecr get-login-password \
                            --region ${AWS_REGION} \
                            | docker login \
                                --username AWS \
                                --password-stdin ${ECR_URL}

                        # Create repo if not exists
                        aws ecr describe-repositories \
                            --repository-names ${APP_NAME} \
                            --region ${AWS_REGION} 2>/dev/null \
                        || aws ecr create-repository \
                            --repository-name ${APP_NAME} \
                            --region ${AWS_REGION}

                        # Tag and push
                        docker tag ${IMAGE_NAME} ${ECR_IMAGE}
                        docker push ${ECR_IMAGE}

                        echo "✅ Pushed: ${ECR_IMAGE}"
                    '''
                }
            }
        }

        // ════════════════════════════════════════════
        // STAGE 8 — RUN DOCKER CONTAINER ON EC2
        // Stops old container → starts new one
        // App will run on port 5000
        // ════════════════════════════════════════════
        stage('8. Run Container') {
            steps {
                sh '''
                    echo "──────────────────────────"
                    echo " RUN CONTAINER ON EC2"
                    echo "──────────────────────────"

                    # Stop and remove old container if running
                    docker stop ${APP_NAME} 2>/dev/null || true
                    docker rm   ${APP_NAME} 2>/dev/null || true

                    # Start new container
                    docker run -d \
                        --name    ${APP_NAME} \
                        --restart unless-stopped \
                        -p 5000:5000 \
                        ${IMAGE_NAME}

                    # Wait and verify
                    sleep 3
                    docker ps | grep ${APP_NAME}

                    echo "✅ Container running → http://EC2-IP:5000"
                '''
            }
        }

        // ════════════════════════════════════════════
        // STAGE 9 — GENERATE HTML REPORT
        // Merges all 3 JSON scan results into
        // one beautiful HTML report
        // Why python? Because Trivy gives 3 separate
        // JSONs — we merge them into 1 HTML
        // ════════════════════════════════════════════
        stage('9. Generate HTML Report') {
            steps {
                sh '''
                    echo "──────────────────────────"
                    echo " GENERATE HTML REPORT"
                    echo "──────────────────────────"

                    python3 ${WORKSPACE}/generate_report.py \
                        ${REPO_JSON} \
                        ${FS_JSON} \
                        ${IMAGE_JSON} \
                        ${HTML_REPORT} \
                        "${APP_NAME}" \
                        "${BUILD_NUMBER}" \
                        "${IMAGE_NAME}"

                    echo ""
                    echo "Report files:"
                    ls -lh ${REPORT_DIR}/

                    echo "✅ HTML report ready"
                '''

                // Show report as clickable link in Jenkins UI
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

        // ════════════════════════════════════════════
        // STAGE 10 — SEND EMAIL
        // Sends HTML report to your Gmail
        // JSON files attached as attachments
        // ════════════════════════════════════════════
        stage('10. Send Email') {
            steps {
                script {
                    // Read the generated HTML file
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

    } // end stages

    // ────────────────────────────────────────────────
    // POST BUILD ACTIONS
    // ────────────────────────────────────────────────
    post {
        always {
            echo "══════════════════════════════"
            echo " BUILD: ${currentBuild.currentResult}"
            echo "══════════════════════════════"
            // Archive all reports as Jenkins artifacts
            archiveArtifacts artifacts: 'reports/**/*',
                             allowEmptyArchive: true
            // Cleanup old docker images to save disk space
            sh '''
                docker rmi ${IMAGE_NAME} || true
                docker image prune -f    || true
            '''
        }

        success {
            echo "✅ PIPELINE PASSED — App is running on EC2:5000"
        }

        failure {
            // Send failure alert email
            emailext(
                subject: "[ALERT] ❌ Pipeline FAILED — ${env.APP_NAME} #${env.BUILD_NUMBER}",
                body: """
                    <h2 style='color:red'>Pipeline Failed!</h2>
                    <p><b>App:</b> ${env.APP_NAME}</p>
                    <p><b>Build:</b> #${env.BUILD_NUMBER}</p>
                    <p><b>Check Jenkins:</b>
                       <a href='${env.BUILD_URL}'>${env.BUILD_URL}</a>
                    </p>
                """,
                mimeType: 'text/html',
                to: "${env.EMAIL_TO}"
            )
        }
    }

}
