resource "aws_iam_policy" "cloudtrail_read" {
  name        = "gcloud-v2-cloudtrail-read"
  description = "Read-only access to CloudTrail logs and their KMS key"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadTrailLogs"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
        ]
        Resource = [
          aws_s3_bucket.trail.arn,
          "${aws_s3_bucket.trail.arn}/*",
        ]
      },
      {
        Sid    = "DecryptTrailLogs"
        Effect = "Allow"
        Action = "kms:Decrypt"
        Resource = aws_kms_key.main.arn
      },
      {
        Sid    = "ReadTrailMetadata"
        Effect = "Allow"
        Action = [
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:LookupEvents",
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cloudtrail_reader" {
  role       = aws_iam_role.cloudtrail_reader.name
  policy_arn = aws_iam_policy.cloudtrail_read.arn
}