CREATE TABLE user (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    userId VARCHAR(255) NOT NULL,
    firstName VARCHAR(255),
    lastName VARCHAR(255),
    username VARCHAR(255),
    password VARCHAR(255),
    email VARCHAR(255),
    profileImageUrl VARCHAR(255),
    lastLoginDate DATE,
    lastLoginDateDisplay DATE,
    joinDate DATE,
    role VARCHAR(255),
    authorities JSON, -- MySQL version >= 5.7.8, sử dụng kiểu JSON cho mảng authorities
    isActive BOOLEAN,
    isNotLocked BOOLEAN
);
