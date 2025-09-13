import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DatabaseModule } from './database/database.module';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { SecurityModule } from './security/security.module';
import { ResilienceModule } from './resilience/resilience.module';
import { AdminModule } from './admin/admin.module';
import { User } from './auth/entities/user.entity';
import { UserProfile } from './users/entities/user-profile.entity';
import { AuditLog } from './common/entities/audit-log.entity';
import { SecurityLog } from './common/entities/security-log.entity';
import { SessionLog } from './common/entities/session-log.entity';
import { CommonModule } from './common/modules/common.module';
import { MinioModule } from './common/modules/minio.module';
import { GuardsModule } from './auth/guards/guards.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get('POSTGRES_HOST') || configService.get('DB_HOST') || 'postgres',
        port: parseInt(configService.get('POSTGRES_PORT') || '5432'),
        username: configService.get('POSTGRES_USER') || 'user',
        password: configService.get('POSTGRES_PASSWORD') || 'password',
        database: configService.get('POSTGRES_DB') || 'postgres',
        entities: [User, UserProfile, AuditLog, SecurityLog, SessionLog],
        synchronize: true, // Solo per sviluppo! In produzione usa migration
        logging: ['error'], // Solo errori
        ssl: false,
      }),
      inject: [ConfigService],
    }),
    CommonModule,
    DatabaseModule,
    AuthModule,
    UsersModule,
    SecurityModule,
    ResilienceModule,
    AdminModule,
    MinioModule,
    GuardsModule
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
