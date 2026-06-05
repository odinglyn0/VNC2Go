const HCAPTCHA_VERIFY_ENDPOINT = "https://api.hcaptcha.com/siteverify"

interface HcaptchaVerifyResponse {
  success: boolean
  "error-codes"?: string[]
  hostname?: string
}

export async function verifyHcaptchaToken(
  token: string,
  secret: string,
  remoteIp?: string,
): Promise<boolean> {
  const body = new URLSearchParams()
  body.set("secret", secret)
  body.set("response", token)
  if (remoteIp) {
    body.set("remoteip", remoteIp)
  }

  const response = await fetch(HCAPTCHA_VERIFY_ENDPOINT, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  })

  if (!response.ok) {
    return false
  }

  const data = (await response.json()) as HcaptchaVerifyResponse
  return data.success === true
}
