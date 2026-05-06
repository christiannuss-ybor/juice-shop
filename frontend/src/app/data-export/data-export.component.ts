/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Component, type OnInit, inject } from '@angular/core'
import { UntypedFormControl, Validators, FormsModule, ReactiveFormsModule } from '@angular/forms'
import { ImageCaptchaService } from '../Services/image-captcha.service'
import { DataSubjectService } from '../Services/data-subject.service'
import { MatButtonModule } from '@angular/material/button'
import { MatInputModule } from '@angular/material/input'
import { MatLabel, MatFormFieldModule, MatHint, MatError } from '@angular/material/form-field'
import { MatRadioGroup, MatRadioButton } from '@angular/material/radio'

import { TranslateModule } from '@ngx-translate/core'
import { MatCardModule } from '@angular/material/card'

import { MatIconModule } from '@angular/material/icon'

@Component({
  selector: 'app-data-export',
  templateUrl: './data-export.component.html',
  styleUrls: ['./data-export.component.scss'],
  imports: [MatCardModule, TranslateModule, MatRadioGroup, FormsModule, ReactiveFormsModule, MatLabel, MatRadioButton, MatFormFieldModule, MatInputModule, MatHint, MatError, MatButtonModule, MatIconModule]
})
export class DataExportComponent implements OnInit {
  private readonly imageCaptchaService = inject(ImageCaptchaService)
  private readonly dataSubjectService = inject(DataSubjectService)

  public captchaControl: UntypedFormControl = new UntypedFormControl('', [Validators.required, Validators.minLength(5)])
  public formatControl: UntypedFormControl = new UntypedFormControl('', [Validators.required])
  public captcha?: string
  private dataRequest: any = undefined
  public confirmation: any
  public error: any
  public lastSuccessfulTry: any
  public presenceOfCaptcha = false
  public userData: any
  ngOnInit (): void {
    this.needCaptcha()
    this.dataRequest = {}
  }

  needCaptcha () {
    const nowTime = new Date()
    const timeOfCaptcha = localStorage.getItem('lstdtxprt') ? new Date(JSON.parse(String(localStorage.getItem('lstdtxprt')))) : new Date(0)
    if (nowTime.getTime() - timeOfCaptcha.getTime() < 300000) {
      this.getNewCaptcha()
      this.presenceOfCaptcha = true
    }
  }

  getNewCaptcha () {
    this.imageCaptchaService.getCaptcha().subscribe((data: any) => {
      // Render the captcha SVG inside an <img> via a data URL so it cannot
      // execute scripts in the host document.
      const svg = String(data?.image ?? '')
      this.captcha = `data:image/svg+xml;base64,${btoa(unescape(encodeURIComponent(svg)))}`
    })
  }

  save () {
    if (this.presenceOfCaptcha) {
      this.dataRequest.answer = this.captchaControl.value
    }
    this.dataRequest.format = this.formatControl.value
    this.dataSubjectService.dataExport(this.dataRequest).subscribe({
      next: (data: any) => {
        this.error = null
        this.confirmation = data.confirmation
        this.userData = data.userData
        // Open the export as a Blob URL so the receiving window cannot script
        // back into this document via document.write.
        const blob = new Blob([String(this.userData ?? '')], { type: 'text/plain' })
        const url = URL.createObjectURL(blob)
        window.open(url, '_blank', 'noopener,noreferrer,width=500')
        this.lastSuccessfulTry = new Date()
        localStorage.setItem('lstdtxprt', JSON.stringify(this.lastSuccessfulTry))
        this.ngOnInit()
        this.resetForm()
      },
      error: (error) => {
        this.error = error.error
        this.confirmation = null
        this.resetFormError()
      }
    })
  }

  resetForm () {
    this.captchaControl.markAsUntouched()
    this.captchaControl.markAsPristine()
    this.captchaControl.setValue('')
    this.formatControl.markAsUntouched()
    this.formatControl.markAsPristine()
    this.formatControl.setValue('')
  }

  resetFormError () {
    this.captchaControl.markAsUntouched()
    this.captchaControl.markAsPristine()
    this.captchaControl.setValue('')
  }
}
