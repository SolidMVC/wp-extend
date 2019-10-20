<?php
/**
 * S.O.L.I.D. MVC additional functions and abbreviations for Main WordPress Formatting API.
 *
 * This is the file of functions, that is missing in wp-includes\formatting.php
 *
 * @see \wp-includes\formatting.php
 * @package WordPress
 */

if(!function_exists('es'))
{
    /**
     * Short name for esc_sql
     * @see esc_sql()
     *
     * @param string $text
     * @return string
     */
    function es($text)
    {
        return esc_sql($text);
    }
}
if(!function_exists('ea'))
{
    /**
     * Short name for esc_attr
     * @see esc_attr()
     *
     * @param string $text
     * @return string
     */
    function ea($text)
    {
        return esc_attr($text);
    }
}

if(!function_exists('esc_br_html'))
{
    /**
     * Escape with line-breaks
     *
     * Related ticked - https://core.trac.wordpress.org/ticket/46188
     *
     * @param string $text
     * @return string
     */
    function esc_br_html($text)
    {
        $escaped_text_array = array_map('esc_html', explode("\n", $text));
        $escaped_multiline_text = implode("<br />", $escaped_text_array);

        return $escaped_multiline_text;
    }
}

if(!function_exists('ebh'))
{
    /**
     * Short name for esc_br_html
     * @see esc_br_html()
     *
     * Related ticked - https://core.trac.wordpress.org/ticket/46188
     *
     * @param string $text
     * @return string
     */
    function ebh($text)
    {
        $escaped_text_array = array_map('esc_html', explode("\n", $text));
        $escaped_multiline_text = implode("<br />", $escaped_text_array);

        return $escaped_multiline_text;
    }
}

if(!function_exists('eh'))
{
    /**
     * Short name for esc_html
     * @see esc_html()
     *
     * @param string $text
     * @return string
     */
    function eh($text)
    {
        return esc_html($text);
    }
}

if(!function_exists('ej'))
{
    /**
     * Short name for esc_js
     * @see esc_js()
     *
     * @param string $text
     * @return string
     */
    function ej($text)
    {
        return esc_js($text);
    }
}

if(!function_exists('et'))
{
    /**
     * Short name for esc_textarea
     * @see esc_textarea()
     *
     * @param string $text
     * @return string
     */
    function et($text)
    {
        return esc_textarea($text);
    }
}