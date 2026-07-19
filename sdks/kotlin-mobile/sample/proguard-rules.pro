# Keep Kotlin serialization metadata for the wire-format DTOs.
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod
-if @kotlinx.serialization.Serializable class **
-keepclassmembers class <1> {
    static <1>$Companion Companion;
}
-if @kotlinx.serialization.Serializable class ** {
    static **$Companion Companion;
}
-keepclasseswithmembers class **$Companion {
    kotlinx.serialization.KSerializer serializer(...);
}

# Credential Manager and Play Integrity are invoked through their public APIs.
-dontwarn org.conscrypt.**
