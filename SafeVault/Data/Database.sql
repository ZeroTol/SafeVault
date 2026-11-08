CREATE DATABASE SafeVault;
GO
USE SafeVault;
GO

CREATE TABLE Users (
                       UserID INT PRIMARY KEY IDENTITY(1,1),
                       Username NVARCHAR(100) NOT NULL UNIQUE,
                       Email NVARCHAR(254) NOT NULL UNIQUE,
                       PasswordHash NVARCHAR(255) NOT NULL,
                       CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);

CREATE TABLE FinancialRecords (
                                  RecordID INT PRIMARY KEY IDENTITY(1,1),
                                  UserID INT NOT NULL,
                                  Amount DECIMAL(18,2) NOT NULL CHECK (Amount >= 0),
                                  Description NVARCHAR(500) NULL,
                                  CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
                                  CONSTRAINT FK_Records_Users FOREIGN KEY (UserID) REFERENCES Users(UserID)
);