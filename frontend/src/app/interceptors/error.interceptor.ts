import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, throwError } from 'rxjs';

export const errorInterceptor: HttpInterceptorFn = (req, next) => {
  return next(req).pipe(
    catchError((error: HttpErrorResponse) => {
      // Tutti i console.log, console.warn, console.error e relativi commenti/documentazione sono stati rimossi da questo file.
      
      let errorMessage = 'An error occurred';
      
      if (error.error instanceof ErrorEvent) {
        // Client-side error
        errorMessage = error.error.message;
      } else {
        // Server-side error
        if (error.error?.message) {
          if (Array.isArray(error.error.message)) {
            errorMessage = error.error.message.join(', ');
          } else {
            errorMessage = error.error.message;
          }
        } else if (error.error?.data?.message) {
          if (Array.isArray(error.error.data.message)) {
            errorMessage = error.error.data.message.join(', ');
          } else {
            errorMessage = error.error.data.message;
          }
        } else if (error.message) {
          errorMessage = error.message;
        }
      }

      // Create a new error object with the processed message
      const processedError = {
        ...error,
        error: {
          ...error.error,
          message: errorMessage
        }
      };

      return throwError(() => processedError);
    })
  );
}; 