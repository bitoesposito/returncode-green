import { Routes } from '@angular/router';
import { authGuard } from './guards/auth.guard';

export const routes: Routes = [
    {
        canActivate: [authGuard],
        path: '',
        loadChildren: () => import('./private/private.module').then(m => m.PrivateModule)
    },
    {
        path: '',
        loadChildren: () => import('./public/public.module').then(m => m.PublicModule)
    },
    {
        path: '**',
        redirectTo: 'login',
        pathMatch: 'full'
    }
];
