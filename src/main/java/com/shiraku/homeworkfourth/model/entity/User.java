package com.shiraku.homeworkfourth.model.entity;

import jakarta.persistence.*;
import lombok.*;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "users")
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode(of = {"id", "login", "email"})
public class User {

    @Id
    @Column(name = "id", updatable = false, nullable = false, columnDefinition = "UUID")
    private UUID id;

    @Column(nullable = false, unique = true,  updatable = false)
    private String login;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false, unique = true)
    private String email;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"))
    @Enumerated(EnumType.STRING)
    @Column(name = "role")
    private Set<RoleName> roles;

    @Column(name = "refresh_token")
    private String refreshToken;

    @Override
    public String toString() {
        System.out.printf("""
                User: \
                login = %s \
                email = %s \
                refreshToken = %s \
                """, login, email, refreshToken);
        return "done";
    }

}
