# Python trace uploader

## Requirements

- Python 3
- Curl

## Installation

1. Download the Python file `cs_upload.py`.
2. Set the environment variables.

### Environment variables

- `CS_ROOT_URL` (required): The root URL of the CAP instance. For SaaS, this is
  <https://analyzer.cryptosense.com>. For an on-premises installation this will be an
  internal URL.
- `CS_API_KEY` (required): A valid API key for your CAP instance. You can get this in the
  web UI by clicking the "API" link in the footer of any page, and then clicking the
  "Reset key" button.
- `CS_CA_CERT` (optional): You won't need this if your server certificate is signed by a
  CA in the standard list used by browsers (and most importantly by `curl`). However if
  you have an on-premises installation using a local self-signed certificate , you will
  need to download it and set `CS_CA_CERT` to where you saved it.

## Usage

Once you have set the environment variables, run the script by:

```
python cs_upload.py --trace-file foo.cst.gz ...
```

### Command-line arguments

- `--trace-file` (required): trace file to upload
- `--trace-name` (optional): name of the trace created. Defaults to the file name.
- `--project-number` (required): the number of the project to upload to. You can find this
  in the web UI if you navigate to that project and then look in the URL, for example in
  `https://[]/project/1022/dashboard`, the trace number is 1022.
- `--profile-number` (optional): the number of the profile you want to use for generating a
  report. If this is not present, no report will be generated. To find the profile number
  you want, navigate to `/organization/profiles` and then select an appropriate profile.
  In `/organization/profiles/211` or `/organization/profiles/211/detail`, the profile
  number is 211.
- `--slot-name` (optional): name of the (existing or not) slot the trace should be uploaded
  to. Without it, the API uses the first existing compatible slot it finds. If none exists 
  yet, it will use the trace type as the name of the new slot.

## How to get your server certificate

If you need the server certificate, you can either:

- Get it from your browser, by going to the CAP web UI and clicking on the padlock, then
  following the prompts for details and export certificate.

- Get it on the command-line using `openssl s_client` as follows:

  ```
  true | openssl s_client -servername <server> -connect <server:port> | openssl x509 > cacert.pem
  ```

  For example, to get the server certificate for the CAP SaaS instance, `server` is
  `analyzer.cryptosense.com` and `port` is 443:

  ```
  true | openssl s_client -servername analyzer.cryptosense.com \
      -connect analyzer.cryptosense.com:443 2>/dev/null | openssl x509 > cacert.pem
  ```
