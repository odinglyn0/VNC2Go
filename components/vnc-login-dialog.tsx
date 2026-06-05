"use client"

import * as React from "react"
import { LockIcon } from "lucide-react"

import type { CredentialField, ResolvedTarget, VncCredentials } from "@/lib/connection"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

interface VncLoginDialogProps {
  open: boolean
  fields: CredentialField[]
  target: ResolvedTarget | null
  onSubmit: (credentials: VncCredentials) => void
  onCancel: () => void
}

const FIELD_LABELS: Record<CredentialField, string> = {
  username: "Username",
  password: "Password",
  target: "Target session",
}

const FIELD_PLACEHOLDERS: Record<CredentialField, string> = {
  username: "Enter the VNC username",
  password: "Enter the VNC password",
  target: "Enter the target session",
}

export function VncLoginDialog({ open, fields, target, onSubmit, onCancel }: VncLoginDialogProps) {
  const [values, setValues] = React.useState<VncCredentials>({})

  React.useEffect(() => {
    if (open) {
      setValues({})
    }
  }, [open, fields])

  const activeFields = fields.length > 0 ? fields : (["password"] as CredentialField[])

  const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const payload: VncCredentials = {}
    for (const field of activeFields) {
      payload[field] = values[field] ?? ""
    }
    onSubmit(payload)
  }

  const handleOpenChange = (next: boolean) => {
    if (!next) {
      onCancel()
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent>
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <LockIcon className="size-4" />
              Authentication required
            </DialogTitle>
            <DialogDescription>
              {target
                ? `${target.display} needs credentials before the session can start.`
                : "This server needs credentials before the session can start."}
            </DialogDescription>
          </DialogHeader>

          <div className="flex flex-col gap-3">
            {activeFields.map((field) => (
              <div key={field} className="flex flex-col gap-1.5">
                <Label htmlFor={`vnc-${field}`}>{FIELD_LABELS[field]}</Label>
                <Input
                  id={`vnc-${field}`}
                  type={field === "password" ? "password" : "text"}
                  autoComplete={field === "password" ? "current-password" : "off"}
                  autoFocus={field === activeFields[0]}
                  placeholder={FIELD_PLACEHOLDERS[field]}
                  value={values[field] ?? ""}
                  onChange={(event) =>
                    setValues((current) => ({ ...current, [field]: event.target.value }))
                  }
                />
              </div>
            ))}
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onCancel}>
              Cancel
            </Button>
            <Button type="submit">Connect</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
