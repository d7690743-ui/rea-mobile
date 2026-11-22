package com.nexos.reamobile;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.UriMatcher;
import android.content.res.AssetFileDescriptor;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import java.io.File;
import java.io.FileNotFoundException;

/**
 * Sirve el ZIP de extracción (cache/rea_extraccion.zip) a otras apps para
 * compartir. Solo framework, sin AndroidX. Solo lectura.
 */
public class ZipShareProvider extends ContentProvider {

    public static final String AUTHORITY = "com.nexos.reamobile.zipshare";
    public static final String FILE_NAME = "rea_extraccion.zip";
    private static final int CODE_ZIP = 1;

    private static final UriMatcher MATCHER = new UriMatcher(UriMatcher.NO_MATCH);

    static {
        MATCHER.addURI(AUTHORITY, FILE_NAME, CODE_ZIP);
    }

    public static Uri zipUri() {
        return new Uri.Builder().scheme("content").authority(AUTHORITY).path(FILE_NAME).build();
    }

    @Override
    public boolean onCreate() {
        return true;
    }

    private File zipFile() throws FileNotFoundException {
        if (getContext() == null) throw new FileNotFoundException("sin contexto");
        File f = new File(getContext().getCacheDir(), FILE_NAME);
        if (!f.isFile()) throw new FileNotFoundException("sin ZIP extraído");
        return f;
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (MATCHER.match(uri) != CODE_ZIP) throw new FileNotFoundException("uri no válido");
        return ParcelFileDescriptor.open(zipFile(), ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override
    public AssetFileDescriptor openAssetFile(Uri uri, String mode) throws FileNotFoundException {
        ParcelFileDescriptor pfd = openFile(uri, mode);
        return new AssetFileDescriptor(pfd, 0, zipFile().length());
    }

    @Override
    public String getType(Uri uri) {
        return "application/zip";
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
                        String sortOrder) {
        try {
            if (MATCHER.match(uri) != CODE_ZIP) return null;
            File f = zipFile();
            MatrixCursor c = new MatrixCursor(
                    new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE});
            c.addRow(new Object[]{f.getName(), f.length()});
            return c;
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException("solo lectura");
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("solo lectura");
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("solo lectura");
    }
}
