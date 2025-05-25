# Task 1. GeneratePasswordHashUsingSalt


I will ignore the security issues realted with the obsolete Rfc2898DeriveBytes class.



I found the following issues:

### 1. Dispose Rfc2898DeriveBytes

```cs
var pbkdf2 = new Rfc2898DeriveBytes(passwordText, salt, iterate);
```
    

As Rfc2898DeriveBytes class extends the DeriveBytes class, and the DeriveBytes implements the IDisposable interface, so
the  Rfc2898DeriveBytes should be disposed, and at the original code is not been disposed, Disposing ensures that any unmanaged resources are released immediately instead of waiting for finalization. It also suppresses the finalizer, preventing the object from living longer than necessary on the heap. By avoiding the finalizer path, we keep these objects in Gen 0 where they can be collected quickly, instead of being promoted to Gen 1 and Gen2.

https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes?view=net-9.0
https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.derivebytes?view=net-9.0


### 2. Dispose Rfc2898DeriveBytes
In case the method GeneratePasswordHashUsingSalt is being called so frecuently, which should be a normal case that it should be used for validating passwords is a common operation, the allocated bytes even when they are few and they are maintained at Gen 0, if we have so many calls to the GeneratePasswordHashUsingSalt method, it can create memory presure, for this reason, without knowning the context I assume it will be a good idea to don't allocate memory here

```cs
    byte[] hash = pbkdf2.GetBytes(20)
```


and

```cs
    byte[] hashBytes = new byte[36];
```


Instead, we can rent a pool that will be used in subsequent calls

```cs
    byte[] buffer = System.Buffers.ArrayPool<byte>.Shared.Rent(saltLength + hashLength);    
```

But we need to keep in mind that we need to return it:

```cs
    ArrayPool<byte>.Shared.Return(buffer);
```

But as sensitive data are keeped in the buffer, we need to remove that data before return it

```cs
    Array.Clear(buffer, 0, totalLength);
    ArrayPool<byte>.Shared.Return(buffer);
```


- This line assume the salt is 16 bytes long:

```cs
    Array.Copy(salt, 0, hashBytes, 0, 16);
```
    

maybe launching an exception if the parameter is not long enough can be a good idea, but we can adjust the code for


```cs
    if (salt is null)
    {
        throw new ArgumentNullException(nameof(salt), "Salt may not be null.");
    }

    if (salt.Length < RequiredSaltLength)
    {
        throw new ArgumentException(
            $"Salt must be at least {RequiredSaltLength} bytes long, but was {salt.Length}.",
            nameof(salt)
        );
    }
```


- I read about how the Span<T> usage can help with memory allocation, but as this was not covered on the theory, I will omite that.