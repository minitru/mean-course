import {
  HttpInterceptor,
  HttpRequest,
  HttpHandler,
  HttpErrorResponse
} from '@angular/common/http';

import { catchError } from 'rxjs/operators';
import { throwError } from 'rxjs';
import { Injectable } from '@angular/core';
import { MatDialog } from '@angular/material';
import { ErrorComponent } from './error/error.component';

@Injectable()
export class ErrorInterceptor implements HttpInterceptor {

  constructor(private dialog: MatDialog ){}

  intercept(req: HttpRequest<any>, next: HttpHandler ) {
    return next.handle(req).pipe(
      catchError((error: HttpErrorResponse) => {
        console.log(error);
        // MONGOOSE ADDS ANOTHER LEVEL OF ERROR FOR THIS INSANITY
        // alert(error.error.error.message);
        this.dialog.open(ErrorComponent);
        return throwError(error);
      })
    );
  }
}
