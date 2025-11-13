package com.devkor.ifive.domain.user.core.entity;

import com.devkor.ifive.morae.global.shared.SoftDeletableAuditable;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "users")
@Getter
public class User extends SoftDeletableAuditable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Setter
    @Column(name = "email")
    private String email;

    @Setter
    @Column(name = "password_hash")
    private String passwordHash;

    @Setter
    @Column(name = "nickname")
    private String nickname;

    @Column(name = "provider")
    private String provider;

    @Column(name = "provider_id")
    private String providerId;

    @Enumerated(EnumType.STRING)
    @Column(name = "signup_status")
    @Setter
    private SignupStatusType signupStatus;

    public static User createUser(String email) {
        User user = new User();
        user.email = email;
        user.signupStatus = SignupStatusType.PROFILE_INCOMPLETE;
        return user;
    }
}
