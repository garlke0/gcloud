resource "aws_kms_key" "main" {
  description             = "gcloud v2 - customer managed key"
  deletion_window_in_days = 14
  enable_key_rotation     = true
}

resource "aws_kms_alias" "main" {
  name          = "alias/gcloud-v2"
  target_key_id = aws_kms_key.main.key_id
}