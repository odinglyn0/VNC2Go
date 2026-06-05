"use client"

import * as React from "react"
import HCaptcha from "@hcaptcha/react-hcaptcha"
import { ShieldCheckIcon } from "lucide-react"
import { toast } from "sonner"

import { getCsrfToken, submitHumanVerification } from "@/lib/connection"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Loader } from "rsuite"

interface HumanGateProps {
  open: boolean
  onVerified: () => void
}

const SITE_KEY = process.env.NEXT_PUBLIC_HCAPTCHA_SITE_KEY ?? "10000000-ffff-ffff-ffff-000000000001"

export function HumanGate({ open, onVerified }: HumanGateProps) {
  const [submitting, setSubmitting] = React.useState(false)
  const captchaRef = React.useRef<HCaptcha | null>(null)

  React.useEffect(() => {
    if (open) {
      void getCsrfToken().catch(() => {
        toast.error("Could not establish a secure session")
      })
    }
  }, [open])

  const handleVerify = React.useCallback(
    async (captchaToken: string) => {
      setSubmitting(true)
      try {
        await submitHumanVerification(captchaToken)
        onVerified()
      } catch (error) {
        const message = error instanceof Error ? error.message : "Verification failed"
        toast.error(message)
        captchaRef.current?.resetCaptcha()
      } finally {
        setSubmitting(false)
      }
    },
    [onVerified],
  )

  return (
    <Dialog open={open}>
      <DialogContent showCloseButton={false} className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldCheckIcon className="size-4" />
            Verify you are human
          </DialogTitle>
          <DialogDescription>
            Complete the challenge below to start a secure VNC session. This protects the
            service from automated abuse.
          </DialogDescription>
        </DialogHeader>

        <div className="flex min-h-20 flex-col items-center justify-center gap-3">
          {submitting ? (
            <Loader size="md" content="Verifying" />
          ) : (
            <HCaptcha
              ref={captchaRef}
              sitekey={SITE_KEY}
              theme="dark"
              onVerify={handleVerify}
              onExpire={() => captchaRef.current?.resetCaptcha()}
              onError={() => toast.error("Captcha error, please retry")}
            />
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
