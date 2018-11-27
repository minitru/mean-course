import {
  HttpInterceptor,
  HttpRequest,
  HttpHandler,
  HttpErrorResponse
} from '@angular/common/http';

import { catchError } from 'rxjs/operators';
import { throwError } from 'rxjs';

export class ErrorInterceptor implements HttpInterceptor {

  intercept(req: HttpRequest<any>, next: HttpHandler ) {

    return next.handle(req).pipe(
      catchError((error: HttpErrorResponse) => {
        console.log(error);
        // MONGOOSE ADDS ANOTHER LEVEL OF ERROR FOR THIS INSANITY
        alert(error.error.error.message);
        return throwError(error);
      })
    );
  }
}
