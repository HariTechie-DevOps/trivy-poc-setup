pipeline {

    agent any

    // ────────────────────────────────────────────────────────
    // CHANGE THESE 4 VALUES ONLY
    // ────────────────────────────────────────────────────────
    environment {
        APP_NAME     = "trivy-poc-app"
        AWS_REGION   = "ap-south-1"
        ECR_ACCOUNT  = "471112521862"          // e.g. 123456789012
        EMAIL_TO     = "s.harisankar21122002@gmail.com"
    }

    // ────────────────────────────────────────────────────────
    // DO NOT CHANGE BELOW THIS LINE
    // ────────────────────────────────────────────────────────
    environment {
        IMAGE_TAG    = "${BUILD_NUMBER}"
        IMAGE_NAME   = "${APP_NAME}:${BUILD_NUMBER}"
        ECR_URL      = "${ECR_ACCOUNT}.dkr.ecr.${AWS_REGION}.amazonaws.com"
        ECR_IMAGE    = "${ECR_URL}/${APP_NAME}:${BUILD_NUMBER}"
        REPORT_DIR   = "${WORKSPACE}/reports"
        REPO_JSON    = "${REPORT_DIR}/repo-scan.json"
        FS_JSON      = "${REPORT_DIR}/fs-scan.json"
        IMAGE_JSON   = "${REPORT_DIR}/image-scan.json"
        HTML_REPORT  = "${REPORT_DIR}/trivy-report.html"
        CACHE_DIR    = "${WORKSPACE}/.trivy-cache"
    }

    options {
        timestamps()
        buildDiscarder(logRotator(numToKeepStr: '5'))
        timeout(time: 40, unit: 'MINUTES')
    }

    stages {

        // ════════════════════════════════════════════
        // STAGE 1 — CHECKOUT
        // ════════════════════════════════════════════
        stage('Checkout') {
            steps {
                checkout scm
                sh '''
                    echo "──────────────────────────────"
                    echo " CODE CHECKED OUT"
                    echo "──────────────────────────────"
                    echo "Branch : $(git rev-parse --abbrev-ref HEAD)"
                    echo "Commit : $(git log --oneline -1)"
                    echo "Files  :"
                    ls -la
                '''
            }
        }

        // ════════════════════════════════════════════
        // STAGE 2 — INSTALL TRIVY + DOWNLOAD DB
        // ════════════════════════════════════════════
        stage('Install Trivy') {
            steps {
                sh '''
                    echo "──────────────────────────────"
                    echo " TRIVY SETUP"
                    echo "──────────────────────────────"

                    mkdir -p ${REPORT_DIR}
                    mkdir -p ${CACHE_DIR}

                    # Install only if not present
                    if ! command -v trivy >/dev/null 2>&1; then
                        echo "Installing Trivy..."
                        sudo apt-get install -y wget gnupg apt-transport-https lsb-release
                        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
                            | sudo apt-key add -
                        echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" \
                            | sudo tee /etc/apt/sources.list.d/trivy.list
                        sudo apt-get update -y
                        sudo apt-get install -y trivy
                        echo "Trivy installed!"
                    else
                        echo "Trivy already installed: $(trivy --version)"
                    fi

                    # Download vulnerability database (cached between builds)
                    echo "Downloading/updating vulnerability DB..."
                    trivy image --download-db-only --cache-dir ${CACHE_DIR}
                    echo "DB ready!"
                '''
            }
        }

        // ════════════════════════════════════════════
        // STAGE 3 — TRIVY REPO SCAN
        // Scans: secrets in code + IaC misconfigs
        //        + vulnerable package files
        // ════════════════════════════════════════════
        stage('Trivy: Repo Scan') {
            steps {
                sh '''
                    echo "──────────────────────────────"
                    echo " TRIVY REPO SCAN"
                    echo " Target : git repository"
                    echo " Finds  : secrets, misconfigs"
                    echo "          vulnerable deps"
                    echo "──────────────────────────────"

                    trivy repo \
                        --cache-dir  ${CACHE_DIR} \
                        --scanners   secret,misconfig,vuln \
                        --format     json \
                        --output     ${REPO_JSON} \
                        --exit-code  0 \
                        . || true

                    echo ""
                    echo "CONSOLE SUMMARY:"
                    trivy repo \
                        --cache-dir  ${CACHE_DIR} \
                        --scanners   secret,misconfig,vuln \
                        --format     table \
                        --exit-code  0 \
                        . || true

                    echo ""
                    echo "✅ Repo scan done → ${REPO_JSON}"
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
        // Scans: all workspace files deeply
        //        Dockerfile misconfigs, secrets
        // ════════════════════════════════════════════
        stage('Trivy: Filesystem Scan') {
            steps {
                sh '''
                    echo "──────────────────────────────"
                    echo " TRIVY FILESYSTEM SCAN"
                    echo " Target : workspace files"
                    echo " Finds  : Dockerfile issues,"
                    echo "          secrets, misconfigs"
                    echo "──────────────────────────────"

                    trivy fs \
                        --cache-dir  ${CACHE_DIR} \
                        --scanners   vuln,secret,misconfig \
                        --format     json \
                        --output     ${FS_JSON} \
                        --exit-code  0 \
                        . || true

                    echo ""
                    echo "CONSOLE SUMMARY:"
                    trivy fs \
                        --cache-dir  ${CACHE_DIR} \
                        --scanners   vuln,secret,misconfig \
                        --format     table \
                        --exit-code  0 \
                        . || true

                    echo ""
                    echo "✅ Filesystem scan done → ${FS_JSON}"
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
        // STAGE 5 — DOCKER BUILD
        // ════════════════════════════════════════════
        stage('Docker: Build') {
            steps {
                sh '''
                    echo "──────────────────────────────"
                    echo " DOCKER BUILD"
                    echo " Image : ${IMAGE_NAME}"
                    echo "──────────────────────────────"

                    docker build -t ${IMAGE_NAME} .

                    echo ""
                    echo "✅ Image built: ${IMAGE_NAME}"
                    docker images | grep ${APP_NAME}
                '''
            }
        }

        // ════════════════════════════════════════════
        // STAGE 6 — TRIVY IMAGE SCAN
        // Scans: OS packages CVEs, app library CVEs,
        //        secrets baked into image layers
        // ════════════════════════════════════════════
        stage('Trivy: Image Scan') {
            steps {
                sh '''
                    echo "──────────────────────────────"
                    echo " TRIVY IMAGE SCAN"
                    echo " Target : ${IMAGE_NAME}"
                    echo " Finds  : OS CVEs, app CVEs,"
                    echo "          baked-in secrets"
                    echo "──────────────────────────────"

                    trivy image \
                        --cache-dir  ${CACHE_DIR} \
                        --scanners   vuln,secret,misconfig \
                        --format     json \
                        --output     ${IMAGE_JSON} \
                        --exit-code  0 \
                        ${IMAGE_NAME} || true

                    echo ""
                    echo "CONSOLE SUMMARY:"
                    trivy image \
                        --cache-dir  ${CACHE_DIR} \
                        --scanners   vuln,secret,misconfig \
                        --format     table \
                        --exit-code  0 \
                        ${IMAGE_NAME} || true

                    echo ""
                    echo "✅ Image scan done → ${IMAGE_JSON}"
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
        // STAGE 7 — PUSH TO ECR
        // ════════════════════════════════════════════
        stage('Push to ECR') {
            steps {
                withCredentials([[
                    $class: 'AmazonWebServicesCredentialsBinding',
                    credentialsId: 'aws-creds',
                    accessKeyVariable: 'AWS_ACCESS_KEY_ID',
                    secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
                ]]) {
                    sh '''
                        echo "──────────────────────────────"
                        echo " PUSH TO ECR"
                        echo " Repo : ${APP_NAME}"
                        echo "──────────────────────────────"

                        # Login to ECR
                        aws ecr get-login-password --region ${AWS_REGION} \
                            | docker login \
                                --username AWS \
                                --password-stdin ${ECR_URL}

                        # Create ECR repo if it doesn't exist
                        aws ecr describe-repositories \
                            --repository-names ${APP_NAME} \
                            --region ${AWS_REGION} 2>/dev/null \
                        || aws ecr create-repository \
                            --repository-name ${APP_NAME} \
                            --region ${AWS_REGION}

                        # Tag and push
                        docker tag ${IMAGE_NAME} ${ECR_IMAGE}
                        docker push ${ECR_IMAGE}

                        echo ""
                        echo "✅ Pushed to ECR: ${ECR_IMAGE}"
                    '''
                }
            }
        }

        // ════════════════════════════════════════════
        // STAGE 8 — RUN DOCKER CONTAINER ON EC2
        // Stops old container and starts new one
        // ════════════════════════════════════════════
        stage('Run Container on EC2') {
            steps {
                sh '''
                    echo "──────────────────────────────"
                    echo " RUN CONTAINER ON EC2"
                    echo "──────────────────────────────"

                    # Stop and remove old container if running
                    docker stop ${APP_NAME} 2>/dev/null || true
                    docker rm   ${APP_NAME} 2>/dev/null || true

                    # Run new container from the built image
                    docker run -d \
                        --name    ${APP_NAME} \
                        --restart unless-stopped \
                        -p 5000:5000 \
                        ${IMAGE_NAME}

                    # Wait 3 seconds and check it started
                    sleep 3
                    docker ps | grep ${APP_NAME}

                    echo ""
                    echo "✅ Container running: ${APP_NAME}"
                    echo "   Access at: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):5000"
                '''
            }
        }

        // ════════════════════════════════════════════
        // STAGE 9 — GENERATE HTML REPORT
        // Merges all 3 scan JSONs → 1 HTML report
        // ════════════════════════════════════════════
        stage('Generate HTML Report') {
            steps {
                sh '''
                    echo "──────────────────────────────"
                    echo " GENERATING HTML REPORT"
                    echo "──────────────────────────────"

                    python3 ${WORKSPACE}/generate_report.py \
                        ${REPO_JSON} \
                        ${FS_JSON} \
                        ${IMAGE_JSON} \
                        ${HTML_REPORT} \
                        "${APP_NAME}" \
                        "${BUILD_NUMBER}" \
                        "${IMAGE_NAME}"

                    echo ""
                    ls -lh ${REPORT_DIR}/
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

        // ════════════════════════════════════════════
        // STAGE 10 — SEND EMAIL
        // Sends full HTML report to team
        // ════════════════════════════════════════════
        stage('Send Email') {
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

    } // end stages

    // ────────────────────────────────────────────────────────
    // POST BUILD
    // ────────────────────────────────────────────────────────
    post {
        always {
            echo "═══════════════════════════════"
            echo " BUILD ${currentBuild.currentResult}"
            echo "═══════════════════════════════"
            archiveArtifacts artifacts: 'reports/**/*',
                             allowEmptyArchive: true
        }
        failure {
            emailext(
                subject: "[ALERT] ❌ Build FAILED — ${env.APP_NAME} #${env.BUILD_NUMBER}",
                body: """<h2 style='color:red'>Pipeline Failed!</h2>
                         <p>App: <b>${env.APP_NAME}</b></p>
                         <p>Build: <b>#${env.BUILD_NUMBER}</b></p>
                         <p>Check: <a href='${env.BUILD_URL}'>${env.BUILD_URL}</a></p>""",
                mimeType: 'text/html',
                to: "${env.EMAIL_TO}"
            )
        }
    }

}
