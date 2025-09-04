<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class PersonalAccessToken extends Model
{
    use HasFactory;

    protected $fillable = [
        'user_id',
        'token_hash',
        'refresh_token_hash',
        'expires_at',
        'refresh_expires_at',
        'last_used_at',
        'ip_address',
        'user_agent',
    ];

    protected $casts = [
        'expires_at' => 'datetime',
        'refresh_expires_at' => 'datetime',
        'last_used_at' => 'datetime',
    ];

    public function user()
    {
        return $this->belongsTo(User::class);
    }

    public function isExpired(): bool
    {
        return $this->expires_at->isPast();
    }

    public function isRefreshExpired(): bool
    {
        return $this->refresh_expires_at->isPast();
    }

    public function canBeRefreshed(): bool
    {
        return !$this->isRefreshExpired();
    }

    public static function findValidToken(string $token): ?self
    {
        $hashedToken = hash('sha256', $token);
        
        return self::where('token_hash', $hashedToken)
            ->where('expires_at', '>', now())
            ->first();
    }

    public static function findValidRefreshToken(string $refreshToken): ?self
    {
        $hashedRefreshToken = hash('sha256', $refreshToken);
        
        return self::where('refresh_token_hash', $hashedRefreshToken)
            ->where('refresh_expires_at', '>', now())
            ->first();
    }

    public static function cleanupExpired(): int
    {
        return self::where('refresh_expires_at', '<', now())->delete();
    }

    public function revoke(): bool
    {
        return $this->delete();
    }

    public function getFormattedLastUsedAttribute(): ?string
    {
        return $this->last_used_at?->diffForHumans();
    }

    public function getIsActiveAttribute(): bool
    {
        return !$this->isExpired();
    }
}